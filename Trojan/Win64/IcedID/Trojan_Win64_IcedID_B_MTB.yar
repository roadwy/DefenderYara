
rule Trojan_Win64_IcedID_B_MTB{
	meta:
		description = "Trojan:Win64/IcedID.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 57 71 76 48 2e 64 6c 6c } //1 jWqvH.dll
		$a_01_1 = {48 56 4d 43 7a 4f 5a 56 6d 41 78 4b 34 6f 61 66 4e 74 } //1 HVMCzOZVmAxK4oafNt
		$a_01_2 = {72 6d 63 6b 36 79 6e 77 79 66 59 34 4e 36 49 49 6e 45 42 } //1 rmck6ynwyfY4N6IInEB
		$a_01_3 = {4c 79 32 46 6b 33 6a 46 36 70 66 62 50 62 4c 50 63 6d 30 59 6c 4c } //1 Ly2Fk3jF6pfbPbLPcm0YlL
		$a_01_4 = {4d 32 7a 35 69 6e 45 38 65 57 68 52 37 31 4a 6c 37 32 36 74 } //1 M2z5inE8eWhR71Jl726t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_B_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 55 6a 61 62 68 73 75 66 79 75 61 73 6b 6a 6e 61 6b 73 6b 66 6a 73 61 } //1 GUjabhsufyuaskjnakskfjsa
		$a_01_1 = {41 69 69 72 6e 48 50 36 77 70 6e 6f 64 48 78 6c 76 45 48 38 } //1 AiirnHP6wpnodHxlvEH8
		$a_01_2 = {47 35 4c 6f 6b 71 79 50 43 54 51 49 67 59 30 6a 7a 6c 50 4d 63 6b 66 70 78 } //1 G5LokqyPCTQIgY0jzlPMckfpx
		$a_01_3 = {59 55 77 6d 63 50 6c 47 42 31 47 53 38 42 38 6b 78 47 62 } //1 YUwmcPlGB1GS8B8kxGb
		$a_01_4 = {66 7a 6c 43 50 32 74 57 76 43 38 6a 4f 78 48 76 64 78 } //1 fzlCP2tWvC8jOxHvdx
		$a_01_5 = {73 34 67 53 6f 59 69 76 49 6b 76 45 4b 61 39 65 } //1 s4gSoYivIkvEKa9e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}