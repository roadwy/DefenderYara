
rule Trojan_BAT_Mokes_AMO_MTB{
	meta:
		description = "Trojan:BAT/Mokes.AMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {18 da 13 07 16 13 08 2b 1d 09 08 11 08 18 6f 4f 01 00 0a 1f 10 28 50 01 00 0a 6f 51 01 00 0a 00 11 08 18 d6 13 08 11 08 11 07 31 dd } //2
		$a_01_1 = {49 6e 74 72 61 73 74 61 74 50 69 65 73 65 } //1 IntrastatPiese
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}