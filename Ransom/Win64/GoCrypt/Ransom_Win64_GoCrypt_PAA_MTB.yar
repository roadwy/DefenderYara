
rule Ransom_Win64_GoCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win64/GoCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d } //01 00  taskkill /F /IM
		$a_01_1 = {68 61 6e 67 75 70 6b 69 6c 6c 65 64 6c 69 73 74 } //01 00  hangupkilledlist
		$a_01_2 = {5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 65 6c 2e 63 6d 64 } //01 00  \Users\Public\Del.cmd
		$a_01_3 = {5c 44 65 6c 2e 63 6d 64 5c 4c 6f 67 2e 63 6d 64 5c 52 45 41 44 4d 45 2e } //01 00  \Del.cmd\Log.cmd\README.
		$a_01_4 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6d 69 63 72 6f 73 6f 66 74 2e 65 78 65 } //01 00  \ProgramData\microsoft.exe
		$a_01_5 = {63 68 61 6e 6e 65 6c 64 65 63 72 79 70 74 74 6f 6f 6c 37 37 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  channeldecrypttool77@gmail.com
		$a_01_6 = {2d 49 6e 66 2d 69 6e 66 2e 49 64 2d 2e 62 61 74 2e 63 6d 64 2e 63 6f 6d 2e 65 78 65 2e 74 78 74 } //00 00  -Inf-inf.Id-.bat.cmd.com.exe.txt
	condition:
		any of ($a_*)
 
}