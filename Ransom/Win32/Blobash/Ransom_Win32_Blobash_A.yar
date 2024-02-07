
rule Ransom_Win32_Blobash_A{
	meta:
		description = "Ransom:Win32/Blobash.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 69 6e 52 41 52 5c 52 61 72 2e 65 78 65 22 20 61 20 2d 72 20 2d 79 20 2d 72 69 31 35 20 2d 64 66 20 2d 6d 30 20 2d 69 6e 75 6c 20 2d 70 25 70 61 73 73 25 20 25 66 69 6c 65 6e 61 6d 65 25 } //0a 00  WinRAR\Rar.exe" a -r -y -ri15 -df -m0 -inul -p%pass% %filename%
		$a_01_1 = {57 69 6e 52 41 52 5c 52 61 72 2e 65 78 65 22 20 63 20 25 66 69 6c 65 6e 61 6d 65 25 20 2d 7a 25 63 6f 6d 6d 65 6e 74 73 66 69 6c 65 25 } //0a 00  WinRAR\Rar.exe" c %filename% -z%commentsfile%
		$a_01_2 = {4c 6f 63 6b 2e 72 61 72 } //00 00  Lock.rar
	condition:
		any of ($a_*)
 
}