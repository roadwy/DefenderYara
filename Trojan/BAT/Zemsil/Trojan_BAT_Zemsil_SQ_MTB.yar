
rule Trojan_BAT_Zemsil_SQ_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 02 09 6f ?? ?? ?? 0a 03 09 07 5d 6f ?? ?? ?? 0a 61 d1 9d 09 17 58 0d 09 06 32 e3 } //2
		$a_01_1 = {78 6f 72 53 74 75 62 2e 65 78 65 } //2 xorStub.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}