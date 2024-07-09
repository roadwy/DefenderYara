
rule Trojan_Win32_Redline_MB_MTB{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c0 f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Redline_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 2f 47 e2 90 0a 37 00 f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MB_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 5c 24 10 89 74 24 24 8b 44 24 2c 01 44 24 24 8b 44 24 18 90 01 44 24 24 8b 44 24 24 89 44 24 20 8b 4c 24 1c 8b 54 24 18 d3 ea 8b cd 8d 44 24 28 89 54 24 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MB_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f7 c1 c1 0d f7 d6 33 fe c1 c8 17 f3 a4 81 f1 09 48 a0 61 33 1d ?? ?? ?? ?? 09 0d ?? ?? ?? ?? 2b c2 21 3d ?? ?? ?? ?? 2b fc c1 c2 1f 81 f3 ec 0c e1 82 0b 15 ?? ?? ?? ?? 09 35 ?? ?? ?? ?? 46 c1 ca 1a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MB_MTB_5{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 64 24 10 8b 44 24 10 b8 ?? ?? ?? ?? f7 a4 24 48 02 00 00 8b 84 24 48 02 00 00 81 ac 24 60 01 00 00 ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 a4 24 cc 00 00 00 8b 84 24 cc 00 00 00 81 ac 24 48 02 00 00 ?? ?? ?? ?? 8a 84 37 ?? ?? ?? ?? 88 04 0e 46 3b 35 ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MB_MTB_6{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 28 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}