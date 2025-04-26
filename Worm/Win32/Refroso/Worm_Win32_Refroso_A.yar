
rule Worm_Win32_Refroso_A{
	meta:
		description = "Worm:Win32/Refroso.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 02 33 f6 8b 54 ?? ?? 33 c0 bb ?? ?? ?? ?? 8a 04 16 33 d2 03 c5 f7 f3 33 c0 8a 04 39 2b c2 79 0f ba ff 00 00 00 2b d0 c1 ea 08 c1 e2 08 03 c2 88 04 39 8b 44 24 1c 46 41 83 c5 09 3b c8 72 bc 8b c7 5f 5d 5b 5e c3 } //1
		$a_00_1 = {2f 63 20 22 66 6f 72 20 2f 4c 20 25 25 61 20 69 6e 20 28 31 2c 31 2c 33 30 29 20 64 6f 20 64 65 6c 20 22 25 73 22 20 26 26 20 69 66 20 65 78 69 73 74 20 22 25 73 22 20 70 69 6e 67 20 2d 6e 20 32 } //1 /c "for /L %%a in (1,1,30) do del "%s" && if exist "%s" ping -n 2
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 5c 4d 69 63 72 6f 73 6f 66 74 5c 5c 57 69 6e 64 6f 77 73 5c 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 5c 52 75 6e 5c 5c } //1 SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}