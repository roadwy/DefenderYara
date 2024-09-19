
rule Trojan_Win32_Zusy_ASK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 33 2e 31 33 36 2e 32 33 34 2e 31 34 30 3a 37 38 39 30 2f 43 6c 6f 75 64 31 35 30 2f 53 53 44 54 48 6f 6f 6b 5f 49 4f 5f 4c 69 6e 6b 2e 74 78 74 } //2 43.136.234.140:7890/Cloud150/SSDTHook_IO_Link.txt
		$a_01_1 = {41 51 41 51 41 51 2e 74 78 74 } //1 AQAQAQ.txt
		$a_01_2 = {6b 74 6b 74 2e 74 78 74 } //1 ktkt.txt
		$a_01_3 = {43 4d 44 20 2f 43 20 53 43 20 44 45 4c 45 54 45 } //1 CMD /C SC DELETE
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Zusy_ASK_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {38 32 37 30 39 37 38 34 35 34 37 35 38 33 39 33 32 37 34 38 33 35 32 37 39 33 32 37 35 37 34 38 } //1 82709784547583932748352793275748
		$a_01_1 = {44 68 68 69 67 67 55 6c 71 73 61 63 61 42 6e 6c 6f 6b 61 54 } //1 DhhiggUlqsacaBnlokaT
		$a_01_2 = {5a 7a 76 7c 65 69 48 6f 64 66 70 6b 62 76 61 6b 6f } //1 Zzv|eiHodfpkbvako
		$a_01_3 = {55 74 65 4e 70 74 32 48 67 61 7a 65 77 72 55 6d 5a 76 74 6a 6c 6f 53 } //1 UteNpt2HgazewrUmZvtjloS
		$a_01_4 = {4b 72 6d 75 68 61 68 6e 55 66 61 7c 6d 6e 6c 46 67 6d 5a 77 6d 6d 45 66 77 6f 74 } //1 KrmuhahnUfa|mnlFgmZwmmEfwot
		$a_01_5 = {c2 01 c6 41 4f 00 44 88 41 5c eb 75 41 b0 01 41 02 d0 88 51 64 3a 51 5a 73 7a 0f b6 c2 46 8a 0c 08 41 80 f9 38 75 16 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=7
 
}