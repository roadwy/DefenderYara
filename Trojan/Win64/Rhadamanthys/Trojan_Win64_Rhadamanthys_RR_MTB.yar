
rule Trojan_Win64_Rhadamanthys_RR_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c0 90 52 48 8d 12 5a 4c 89 c0 66 90 80 30 72 48 89 c9 48 87 db 48 83 c0 01 48 39 c8 75 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Rhadamanthys_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8d [0-05] 0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 4d 8d 36 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Rhadamanthys_RR_MTB_3{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 8d 05 [0-05] 89 d9 31 c1 89 c8 31 d0 89 05 ?? ?? ?? ?? eb [0-05] 53 48 83 ec 20 48 89 cb b9 14 00 00 00 e8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Rhadamanthys_RR_MTB_4{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 f0 48 8b 45 f8 48 01 d0 44 0f b6 00 b9 00 01 00 00 48 8b 45 f8 ba 00 00 00 00 48 f7 f1 48 8d [0-06] 0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Rhadamanthys_RR_MTB_5{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 f0 48 8b 45 f8 48 01 d0 44 0f b6 00 b9 00 01 00 00 48 8b 45 f8 ba 00 00 00 00 48 f7 f1 48 8d 05 58 54 00 00 0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}