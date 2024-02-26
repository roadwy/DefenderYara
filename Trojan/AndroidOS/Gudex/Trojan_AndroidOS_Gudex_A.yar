
rule Trojan_AndroidOS_Gudex_A{
	meta:
		description = "Trojan:AndroidOS/Gudex.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 75 6e 72 65 61 6c 2e 69 6e 6a 2e 4d 61 69 6e 53 65 72 76 69 63 65 } //02 00  com.unreal.inj.MainService
		$a_01_1 = {2f 58 41 58 20 36 31 36 } //00 00  /XAX 616
	condition:
		any of ($a_*)
 
}