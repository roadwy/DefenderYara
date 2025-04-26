
rule TrojanDropper_Win32_BcryptInject_A_MTB{
	meta:
		description = "TrojanDropper:Win32/BcryptInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 70 79 20 73 2e 64 6c 6c 20 75 2e 64 6c 6c 3e 6e 75 6c } //1 copy s.dll u.dll>nul
		$a_01_1 = {74 79 70 65 20 25 30 20 3e 76 69 72 2e 62 61 74 } //1 type %0 >vir.bat
		$a_01_2 = {65 63 68 6f 20 25 25 61 3e 3e 76 69 72 2e 62 61 74 } //1 echo %%a>>vir.bat
		$a_01_3 = {69 66 20 6e 6f 74 20 65 78 69 73 74 20 25 25 61 2e 63 6f 6d 20 75 2e 64 6c 6c 20 2d 62 61 74 20 20 76 69 72 2e 62 61 74 20 2d 73 61 76 65 20 25 25 61 2e 63 6f 6d 20 2d 69 6e 63 6c 75 64 65 20 73 2e 64 6c 6c 20 2d 6f 76 65 72 77 72 69 74 65 20 2d 6e 6f 64 65 6c 65 74 65 } //1 if not exist %%a.com u.dll -bat  vir.bat -save %%a.com -include s.dll -overwrite -nodelete
		$a_01_4 = {64 65 6c 20 73 2e 64 6c 6c 20 2f 71 } //1 del s.dll /q
		$a_01_5 = {64 65 6c 20 76 69 72 2e 62 61 74 20 2f 71 } //1 del vir.bat /q
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}