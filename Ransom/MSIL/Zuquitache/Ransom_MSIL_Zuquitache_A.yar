
rule Ransom_MSIL_Zuquitache_A{
	meta:
		description = "Ransom:MSIL/Zuquitache.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {48 00 69 00 20 00 42 00 75 00 64 00 64 00 79 00 21 00 00 0f 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 } //1 Hi Buddy!ༀmessage
		$a_80_1 = {2f 52 45 41 44 5f 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 2e 74 78 74 } ///READ_ME_FOR_DECRYPT.txt  1
		$a_80_2 = {2f 52 45 41 44 20 4d 45 20 46 4f 52 20 44 45 43 52 59 50 54 2e 74 78 74 } ///READ ME FOR DECRYPT.txt  1
		$a_03_3 = {2f 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 74 00 78 00 74 00 ?? ?? 61 00 6d 00 6f 00 75 00 6e 00 74 00 } //1
		$a_00_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 00 0f 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 00 0f 2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //2 DisableTaskMgrༀtaskmgrༀ.locked
		$a_00_5 = {62 00 74 00 63 00 3d 00 00 0b 26 00 77 00 69 00 64 00 3d 00 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*3) >=5
 
}