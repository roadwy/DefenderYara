
rule Worm_Win32_Taterf_DI_dll{
	meta:
		description = "Worm:Win32/Taterf.DI!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 2e 5c } //1 shell\open\Command=rundll32.exe .\
		$a_00_1 = {43 4c 53 49 44 5c 7b 30 30 31 30 42 42 30 43 2d 32 46 38 35 2d 34 36 43 33 2d 42 30 36 41 2d 30 46 38 37 42 42 30 38 36 34 36 43 7d 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 CLSID\{0010BB0C-2F85-46C3-B06A-0F87BB08646C}\InProcServer32
		$a_03_2 = {b0 65 aa b0 78 aa b0 70 aa b0 6c aa b0 6f aa b0 72 aa b0 65 aa b0 72 aa b0 2e aa b0 65 aa b0 78 aa b0 65 aa 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}