
rule Trojan_Win32_Tinba_MK_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e2 03 8b 45 ec c1 e8 1d 0b d0 89 55 ec 0f be 4d fc 0f be 55 e0 2b ca 8b 45 cc 8d 8c 08 cf fe ff ff 89 4d cc 0f be 55 e8 8b 45 94 0f af c2 } //25
		$a_01_1 = {81 f2 a7 bb 3c 00 89 55 ec 0f be 45 98 0f be 4d b4 0f af c1 8b 55 cc 2b d0 8b 45 b0 2b c2 } //10
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}