
rule Trojan_AndroidOS_Hiddad_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddad.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6d 2f 78 74 72 61 63 6b 2f 4c 6f 6c 61 41 63 74 69 76 69 74 79 } //01 00  am/xtrack/LolaActivity
		$a_01_1 = {2e 6e 63 6f 6e 66 68 7a 2e 63 6f 6d } //01 00  .nconfhz.com
		$a_01_2 = {49 4e 54 45 4e 54 5f 41 43 54 49 4f 4e 5f 41 44 5f 53 48 4f 57 } //01 00  INTENT_ACTION_AD_SHOW
		$a_01_3 = {61 64 4c 6f 61 64 65 64 } //01 00  adLoaded
		$a_01_4 = {6c 6f 63 6b 5f 65 6e 61 62 6c 65 5f 61 64 } //00 00  lock_enable_ad
	condition:
		any of ($a_*)
 
}