
rule Trojan_Win64_Convagent_ARA_MTB{
	meta:
		description = "Trojan:Win64/Convagent.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 41 6e 74 69 52 65 76 65 72 73 65 54 65 73 74 5c } //2 \AntiReverseTest\
		$a_01_1 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 50 61 73 73 54 68 72 75 } //2 -WindowStyle Hidden -PassThru
		$a_01_2 = {73 74 61 72 74 20 2f 62 20 50 6f 77 65 72 53 68 65 6c 6c 2e 65 78 65 } //2 start /b PowerShell.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}