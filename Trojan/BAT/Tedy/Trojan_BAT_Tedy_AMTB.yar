
rule Trojan_BAT_Tedy_AMTB{
	meta:
		description = "Trojan:BAT/Tedy!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 63 6d 64 2e 65 78 65 20 2d 41 72 67 75 6d 65 6e 74 4c 69 73 74 20 27 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 52 65 67 41 73 6d 2e 65 78 65 20 2f 46 20 26 20 74 61 73 6b 6b 69 6c 6c } //Start-Process cmd.exe -ArgumentList '/c taskkill /IM RegAsm.exe /F & taskkill  1
		$a_80_1 = {2f 49 4d 20 56 62 63 2e 65 78 65 20 2f 46 20 26 20 74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 4d 73 42 75 69 6c 64 2e 65 78 65 20 2f 46 27 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 57 61 69 74 } ///IM Vbc.exe /F & taskkill /IM MsBuild.exe /F' -WindowStyle Hidden -Wait  1
		$a_80_2 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 69 66 20 28 28 47 65 74 2d 4c 6f 63 61 74 69 6f 6e 29 2e 50 61 74 68 20 2d 6e 65 } //-WindowStyle Hidden if ((Get-Location).Path -ne  1
		$a_80_3 = {47 65 74 2d 43 68 69 6c 64 49 74 65 6d 20 2a 2e 76 62 73 20 7c 20 53 6f 72 74 2d 4f 62 6a 65 63 74 20 43 72 65 61 74 69 6f 6e 54 69 6d 65 20 2d 44 65 73 63 65 6e 64 69 6e 67 20 7c 20 53 65 6c 65 63 74 2d 4f 62 6a 65 63 74 20 2d 46 69 72 73 74 20 31 29 20 7c 20 43 6f 70 79 2d 49 74 65 6d 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e } //Get-ChildItem *.vbs | Sort-Object CreationTime -Descending | Select-Object -First 1) | Copy-Item -Destination  1
		$a_80_4 = {46 6f 72 63 65 } //Force  1
		$a_80_5 = {77 72 66 66 69 74 65 2e 62 61 74 } //wrffite.bat  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}