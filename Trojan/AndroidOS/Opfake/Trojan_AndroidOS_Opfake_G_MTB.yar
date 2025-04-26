
rule Trojan_AndroidOS_Opfake_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 50 72 69 63 65 73 } //1 smsPrices
		$a_01_1 = {2e 72 65 63 65 69 76 65 72 73 2e 41 64 6d 69 6e 54 72 61 63 6b 65 72 } //1 .receivers.AdminTracker
		$a_01_2 = {63 6f 6d 2f 61 70 70 73 2f 70 61 63 6b } //1 com/apps/pack
		$a_01_3 = {72 65 65 6e 61 62 6c 65 4b 65 79 67 75 61 72 64 } //1 reenableKeyguard
		$a_01_4 = {67 65 74 54 61 73 6b 2e 70 68 70 3f } //1 getTask.php?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}