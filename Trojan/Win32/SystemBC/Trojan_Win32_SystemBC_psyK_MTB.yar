
rule Trojan_Win32_SystemBC_psyK_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 01 ff 50 20 83 c6 04 3b 35 10 dd 46 00 72 ea ff 15 88 d1 45 00 6a 0c a3 28 e8 46 00 89 3d 2c } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}