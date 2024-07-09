
rule Trojan_Win64_Tedy_NTD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c3 48 03 c0 49 83 24 c4 00 33 c0 eb db 48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 57 48 83 ec 20 bf ?? ?? ?? ?? 48 8d 1d 60 f5 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Tedy_NTD_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 84 23 01 00 00 85 c9 75 4a c7 05 9f 9d 01 00 ?? ?? ?? ?? 48 8d 15 e0 f0 00 00 48 8d 0d a1 f0 00 00 e8 44 4a } //5
		$a_01_1 = {3a 2f 2f 66 74 70 2e 32 71 6b 2e 63 6e 2f 48 44 31 2d 32 2e 64 6c 6c } //1 ://ftp.2qk.cn/HD1-2.dll
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win64_Tedy_NTD_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6f 64 20 70 61 63 7a 6b 65 20 42 6c 61 7a 69 6e 67 50 61 63 6b } //1 pod paczke BlazingPack
		$a_01_1 = {62 6c 65 64 6e 61 20 6c 69 63 65 6e 63 6a 61 20 6c 75 62 20 6a 65 73 74 65 73 20 7a 6a 65 62 61 6e 79 } //1 bledna licencja lub jestes zjebany
		$a_01_2 = {76 69 6c 6c 61 64 65 6e 74 65 78 2e 70 6c } //1 villadentex.pl
		$a_01_3 = {43 6c 61 73 73 65 73 20 6c 6f 61 64 65 64 20 73 75 63 63 65 73 66 75 6c 79 } //1 Classes loaded succesfuly
		$a_01_4 = {70 6f 64 20 70 61 63 7a 6b 65 20 4c 75 6e 61 72 20 43 6c 69 65 6e 74 } //1 pod paczke Lunar Client
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}