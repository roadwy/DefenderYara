
rule Trojan_BAT_Lazy_KAZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 } //1
		$a_01_1 = {45 6e 63 5f 4f 75 74 70 75 74 2e 65 78 65 } //1 Enc_Output.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}