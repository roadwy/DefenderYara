
rule Trojan_Win32_Emotet_D_MTB{
	meta:
		description = "Trojan:Win32/Emotet.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 4a 0d ce 09 [0-10] e8 ?? ?? ff ff [0-10] e8 ?? ?? ff ff 90 08 00 08 6a 40 68 00 10 00 00 [0-10] ff d0 [0-10] e8 ?? ?? 00 00 [0-10] 68 91 01 00 00 50 e8 ?? ?? ff ff 83 c4 18 83 78 ?? 08 72 } //1
		$a_02_1 = {68 4a 0d ce 09 [0-10] e8 ?? ?? ff ff [0-10] e8 ?? ?? ff ff 90 08 00 08 6a 40 68 00 10 00 00 [0-10] ff 55 [0-10] e8 ?? ?? 00 00 [0-10] 68 91 01 00 00 50 e8 ?? ?? ff ff 83 c4 18 83 78 ?? 08 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}