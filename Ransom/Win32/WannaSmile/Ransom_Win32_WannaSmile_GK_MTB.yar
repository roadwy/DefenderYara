
rule Ransom_Win32_WannaSmile_GK_MTB{
	meta:
		description = "Ransom:Win32/WannaSmile.GK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 04 31 8d 49 04 31 41 fc 8b 44 19 fc 31 44 11 fc 83 ef 01 } //01 00 
		$a_01_1 = {4d 79 45 6e 63 72 79 70 74 65 72 32 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}