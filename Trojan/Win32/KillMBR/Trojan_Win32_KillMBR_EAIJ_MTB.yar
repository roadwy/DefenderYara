
rule Trojan_Win32_KillMBR_EAIJ_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EAIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 ea 0b 80 e2 06 32 d0 8a ca c0 e2 02 02 ca 02 c9 88 8c 05 f8 f3 fa ff 40 3d fe 0b 05 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}