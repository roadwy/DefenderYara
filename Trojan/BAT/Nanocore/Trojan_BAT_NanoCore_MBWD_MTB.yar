
rule Trojan_BAT_NanoCore_MBWD_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 0d 06 09 03 08 18 6f ?? 00 00 0a 1f ?? 28 ?? 00 00 0a 07 09 07 8e 69 5d 91 61 d2 9c } //2
		$a_01_1 = {72 61 63 6f 6f 6e 2e 65 78 65 } //1 racoon.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}