
rule Worm_Win32_Autorun_gen_BP{
	meta:
		description = "Worm:Win32/Autorun.gen!BP,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 5c 69 6e 66 65 63 74 65 64 5c 63 6f 6d 6d 61 6e 64 3d 70 72 6f 74 65 63 74 6f 72 2e 65 78 65 } //1 shell\infected\command=protector.exe
		$a_01_1 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \autorun.inf
		$a_01_2 = {5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 44 20 42 75 72 6e 69 6e 67 5c 70 72 6f 74 65 63 74 6f 72 2e 65 78 65 } //1 \Local Settings\Application Data\Microsoft\CD Burning\protector.exe
		$a_01_3 = {77 61 7a 61 61 61 70 6c 64 73 66 73 64 66 } //1 wazaaapldsfsdf
		$a_01_4 = {44 6f 6f 6d 73 64 61 79 20 48 61 73 20 43 6f 6d 65 2e 2e 2e } //1 Doomsday Has Come...
		$a_01_5 = {59 4f 55 20 41 52 45 20 69 4e 46 45 43 54 45 44 20 42 59 20 52 41 56 4f 5f 35 30 30 32 } //1 YOU ARE iNFECTED BY RAVO_5002
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}