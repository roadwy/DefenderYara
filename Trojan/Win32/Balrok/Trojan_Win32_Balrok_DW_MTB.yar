
rule Trojan_Win32_Balrok_DW_MTB{
	meta:
		description = "Trojan:Win32/Balrok.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 6f 6d 20 43 6c 61 6e 63 79 73 20 47 68 6f 73 74 20 52 65 63 6f 6e 20 2d 20 44 65 73 65 72 74 20 53 69 65 67 65 20 6e 6f 20 63 64 20 63 72 61 63 6b 2e 65 78 65 } //1 Tom Clancys Ghost Recon - Desert Siege no cd crack.exe
		$a_01_1 = {53 70 6f 6e 67 65 20 42 6f 62 20 53 71 75 61 72 65 20 50 61 6e 74 73 20 2d 20 4f 70 65 72 61 74 69 6f 6e 20 4b 72 61 62 62 79 20 50 61 74 74 79 20 6e 6f 20 63 64 20 63 72 61 63 6b 2e 65 78 65 } //1 Sponge Bob Square Pants - Operation Krabby Patty no cd crack.exe
		$a_01_2 = {62 61 6c 52 4f 4b 5f 73 74 61 74 65 5b 43 72 61 63 6b 5d 2e 45 58 45 } //1 balROK_state[Crack].EXE
		$a_01_3 = {53 74 61 72 20 57 61 72 73 20 2d 20 4a 65 64 69 20 4b 6e 69 67 68 74 20 2d 20 4a 65 64 69 20 41 63 61 64 65 6d 79 20 6e 6f 20 63 64 20 63 72 61 63 6b 2e 65 78 65 } //1 Star Wars - Jedi Knight - Jedi Academy no cd crack.exe
		$a_01_4 = {43 6f 6d 6d 61 6e 64 20 26 20 43 6f 6e 71 75 65 72 20 2d 20 47 65 6e 65 72 61 6c 73 20 6e 6f 20 63 64 20 63 72 61 63 6b 2e 65 78 65 } //1 Command & Conquer - Generals no cd crack.exe
		$a_01_5 = {52 6f 6c 6c 65 72 43 6f 61 73 74 65 72 20 54 79 63 6f 6f 6e 20 4e 4f 20 43 44 20 43 72 61 63 6b 20 28 49 6e 63 6c 75 64 69 6e 67 20 41 74 74 72 61 63 74 69 6f 6e 73 20 50 61 63 6b 29 2e 65 78 65 } //1 RollerCoaster Tycoon NO CD Crack (Including Attractions Pack).exe
		$a_01_6 = {43 61 6c 6c 20 4f 66 20 44 75 74 79 20 6e 6f 20 63 64 20 63 72 61 63 6b 2e 65 78 65 } //1 Call Of Duty no cd crack.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}