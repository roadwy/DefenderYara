
rule Trojan_Win32_FileSender_B{
	meta:
		description = "Trojan:Win32/FileSender.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 2d 50 72 6f 63 65 73 73 20 7c 20 57 68 65 72 65 2d 4f 62 6a 65 63 74 20 7b 7b 24 5f 2e 50 61 74 68 20 2d 6c 69 6b 65 20 24 70 61 74 68 7d 7d 20 7c 20 } //Get-Process | Where-Object {{$_.Path -like $path}} |   5
		$a_80_1 = {53 74 6f 70 2d 50 72 6f 63 65 73 73 20 2d 46 6f 72 63 65 3b 5b 62 79 74 65 5b 5d 5d 24 61 72 72 20 3d 20 6e 65 77 2d 6f 62 6a 65 63 74 20 62 79 74 65 5b 5d 20 7b 31 7d 3b 53 65 74 2d 43 6f 6e 74 65 6e 74 20 2d 50 61 74 68 20 24 70 61 74 68 20 2d 56 61 6c 75 65 20 24 61 72 72 3b 52 65 6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 20 24 70 61 74 68 3b } //Stop-Process -Force;[byte[]]$arr = new-object byte[] {1};Set-Content -Path $path -Value $arr;Remove-Item -Path $path;  5
		$a_80_2 = {63 3a 5c 77 6f 72 6b 5c 66 69 6c 65 5f 73 65 6e 64 65 72 5c 73 65 6e 64 65 72 32 5c 73 65 6e 64 65 72 32 5c 62 69 6e 5c 72 65 6c 65 61 73 65 5c 73 65 6e 64 65 72 32 2e 70 64 62 } //c:\work\file_sender\sender2\sender2\bin\release\sender2.pdb  5
		$a_80_3 = {21 73 65 6e 64 65 72 32 2e 75 70 6c 6f 61 64 2b 3c 69 73 43 6f 6e 6e 65 63 74 65 64 3e } //!sender2.upload+<isConnected>  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5) >=10
 
}