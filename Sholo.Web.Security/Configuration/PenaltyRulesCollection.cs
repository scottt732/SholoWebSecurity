using System.Configuration;
using Sholo.Web.Security.Penalties;

namespace Sholo.Web.Security.Configuration
{
    public class PenaltyRulesCollection : ConfigurationElementCollection
    {
        public override ConfigurationElementCollectionType CollectionType
        {
            get
            {
                return ConfigurationElementCollectionType.AddRemoveClearMap;
            }
        }

        public PenaltyRuleElement this[int index]
        {
            get { return (PenaltyRuleElement)BaseGet(index); }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }
                BaseAdd(index, value);
            }
        }

        public void Add(PenaltyRuleElement element)
        {
            BaseAdd(element);
        }

        public void Clear()
        {
            BaseClear();
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new PenaltyRuleElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((PenaltyRuleElement)element).Name;
        }

        public void Remove(string name)
        {
            BaseRemove(name);
        }

        public void RemoveAt(int index)
        {
            BaseRemoveAt(index);
        }
    }
}