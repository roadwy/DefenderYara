
rule Trojan_Win32_Flystudio_NF_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 39 1d ?? ?? ?? ?? 56 57 75 05 e8 44 fd ff ff be b0 f1 4d } //5
		$a_03_1 = {a1 64 08 4e 00 89 35 ?? ?? ?? ?? 8b fe 38 18 74 02 8b f8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_Flystudio_NF_MTB_2{
	meta:
		description = "Trojan:Win32/Flystudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb de 8d 45 ?? 50 ff 15 9c 21 47 00 66 83 7d ea 00 0f 84 d1 } //5
		$a_03_1 = {83 f9 ff 74 38 8a 03 a8 01 74 32 a8 ?? 75 0b 51 ff 15 50 23 47 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_Flystudio_NF_MTB_3{
	meta:
		description = "Trojan:Win32/Flystudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {3b f0 73 1e 80 66 04 00 83 0e ?? 83 66 08 00 c6 46 05 ?? a1 60 bc 61 00 83 c6 ?? 05 80 04 00 00 eb de } //5
		$a_03_1 = {eb de 8d 45 ?? 50 ff 15 94 51 49 00 66 83 7d ?? 00 0f 84 d1 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}