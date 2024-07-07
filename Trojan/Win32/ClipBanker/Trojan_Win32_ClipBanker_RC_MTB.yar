
rule Trojan_Win32_ClipBanker_RC_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 4e 66 75 59 55 38 6d 54 67 73 4d 56 4c 45 56 57 51 4a 6d 4c 6a 45 50 6d 57 35 4e 68 73 46 77 66 46 } //1 TNfuYU8mTgsMVLEVWQJmLjEPmW5NhsFwfF
		$a_01_1 = {30 78 36 33 44 30 36 34 63 42 63 36 65 35 32 39 35 31 64 65 35 33 37 33 35 32 32 37 38 46 32 62 44 35 35 36 41 31 32 33 35 43 } //1 0x63D064cBc6e52951de537352278F2bD556A1235C
		$a_01_2 = {88 b6 5c e5 9f ba e7 a1 80 e5 8a 9f e8 83 bd 5c } //1
		$a_01_3 = {52 65 6c 65 61 73 65 5c 43 6c 69 70 70 65 72 2e 70 64 62 } //1 Release\Clipper.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_ClipBanker_RC_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 63 31 71 35 30 32 76 61 66 6d 6d 72 35 70 72 74 79 66 65 71 63 75 74 71 30 7a 7a 64 72 6b 7a 6e 35 75 32 71 72 32 79 32 6a } //1 bc1q502vafmmr5prtyfeqcutq0zzdrkzn5u2qr2y2j
		$a_01_1 = {30 78 36 33 39 46 34 35 64 34 66 31 61 46 37 37 36 38 66 44 39 34 35 64 62 35 33 43 30 66 32 64 33 31 39 38 44 36 33 33 34 36 } //1 0x639F45d4f1aF7768fD945db53C0f2d3198D63346
		$a_01_2 = {6c 74 63 31 71 76 71 78 6c 65 39 37 65 63 78 32 39 61 61 36 68 6e 72 65 66 72 74 77 74 76 79 6b 39 65 30 77 37 33 30 6b 70 79 78 } //1 ltc1qvqxle97ecx29aa6hnrefrtwtvyk9e0w730kpyx
		$a_01_3 = {43 6c 69 70 70 65 72 2d 35 30 35 39 38 31 31 37 35 31 5c 63 6c 69 70 70 65 72 32 2e 30 2e 70 64 62 } //1 Clipper-5059811751\clipper2.0.pdb
		$a_01_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}