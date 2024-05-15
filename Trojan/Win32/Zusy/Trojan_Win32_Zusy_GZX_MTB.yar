
rule Trojan_Win32_Zusy_GZX_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {41 f6 dd 45 32 cd 46 89 14 2c 44 0f a3 d6 41 8b 34 24 } //05 00 
		$a_01_1 = {c0 e3 0d 00 0f 84 3f e4 02 00 8a d9 80 } //00 00 
	condition:
		any of ($a_*)
 
}