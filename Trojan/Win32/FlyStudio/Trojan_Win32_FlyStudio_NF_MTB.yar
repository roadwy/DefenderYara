
rule Trojan_Win32_FlyStudio_NF_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 39 1d 90 01 04 56 57 75 05 e8 44 fd ff ff be b0 f1 4d 90 00 } //5
		$a_03_1 = {a1 64 08 4e 00 89 35 90 01 04 8b fe 38 18 74 02 8b f8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_FlyStudio_NF_MTB_2{
	meta:
		description = "Trojan:Win32/FlyStudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb de 8d 45 90 01 01 50 ff 15 9c 21 47 00 66 83 7d ea 00 0f 84 d1 90 00 } //5
		$a_03_1 = {83 f9 ff 74 38 8a 03 a8 01 74 32 a8 90 01 01 75 0b 51 ff 15 50 23 47 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_FlyStudio_NF_MTB_3{
	meta:
		description = "Trojan:Win32/FlyStudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {3b f0 73 1e 80 66 04 00 83 0e 90 01 01 83 66 08 00 c6 46 05 90 01 01 a1 60 bc 61 00 83 c6 90 01 01 05 80 04 00 00 eb de 90 00 } //5
		$a_03_1 = {eb de 8d 45 90 01 01 50 ff 15 94 51 49 00 66 83 7d 90 01 01 00 0f 84 d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}