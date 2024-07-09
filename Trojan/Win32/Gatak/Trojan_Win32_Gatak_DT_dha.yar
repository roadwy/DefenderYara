
rule Trojan_Win32_Gatak_DT_dha{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c7 89 7d ?? 29 f1 8b 45 ?? 8a 5d ?? 80 cb ?? 88 5d ?? 89 4d ?? 8a 5d ?? 38 1c 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=20
 
}
rule Trojan_Win32_Gatak_DT_dha_2{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f0 31 c6 45 f1 32 c6 45 f2 33 c6 45 f3 34 c6 45 f4 35 c6 45 f5 35 c6 45 f6 34 c6 45 f7 33 c6 45 f8 32 c6 45 f9 31 88 5d fa ff 15 ?? ?? ?? ?? 66 85 c0 } //5
	condition:
		((#a_03_0  & 1)*5) >=100
 
}
rule Trojan_Win32_Gatak_DT_dha_3{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 4d 44 20 2f 43 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 44 45 4c } //5 CMD /C SYSTEMINFO && SYSTEMINFO && SYSTEMINFO && SYSTEMINFO && SYSTEMINFO && DEL
	condition:
		((#a_01_0  & 1)*5) >=100
 
}
rule Trojan_Win32_Gatak_DT_dha_4{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f8 00 c6 45 d8 4d c6 45 d9 70 c6 45 da 53 c6 45 db 74 c6 45 dc 61 c6 45 dd 72 c6 45 de 74 c6 45 df 50 c6 45 e0 72 c6 45 e1 6f c6 45 e2 63 c6 45 e3 65 c6 45 e4 73 c6 45 e5 73 c6 45 e6 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=100
 
}