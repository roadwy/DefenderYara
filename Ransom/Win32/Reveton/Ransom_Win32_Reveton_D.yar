
rule Ransom_Win32_Reveton_D{
	meta:
		description = "Ransom:Win32/Reveton.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 38 01 00 00 8d 85 ac fe ff ff 50 53 e8 ?? ?? ?? ?? 40 0f 84 ?? ?? ?? ?? 6a 00 68 00 01 00 00 8d 85 ac fd ff ff 50 53 e8 ?? ?? ?? ?? 3d 00 01 00 00 } //1
		$a_00_1 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 45 4e 53 5c 50 61 72 61 6d 65 74 65 72 73 5c 53 65 72 76 69 63 65 44 6c 6c } //1 CurrentControlSet\Services\SENS\Parameters\ServiceDll
		$a_00_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 5c 53 74 61 72 74 75 70 } //1 CurrentVersion\Explorer\Shell Folders\Startup
		$a_00_3 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 5c 43 6f 6d 6d 6f 6e 20 41 70 70 44 61 74 61 } //1 CurrentVersion\Explorer\Shell Folders\Common AppData
		$a_00_4 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 63 74 66 6d 6f 6e 2e 65 78 65 } //1 Windows\CurrentVersion\Run\ctfmon.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}