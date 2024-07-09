
rule Trojan_Win32_Tofsee_PVI_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 18 e8 ?? ?? ?? ?? 30 06 b8 01 00 00 00 29 85 f4 f7 ff ff 8b 85 f4 f7 ff ff 85 c0 79 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}