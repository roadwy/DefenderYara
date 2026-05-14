
rule Trojan_Win32_Tedy_SKP_MTB{
	meta:
		description = "Trojan:Win32/Tedy.SKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 88 14 09 44 32 1c 08 41 8d 41 01 44 88 1c 08 41 8d 40 02 32 1c 08 41 8d 41 02 88 1c 08 41 8d 40 03 40 32 3c 08 41 8d 41 03 40 88 3c 08 83 fe 3c 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}