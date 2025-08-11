
rule Trojan_BAT_Evader_PGE_MTB{
	meta:
		description = "Trojan:BAT/Evader.PGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 6d 6f 20 70 73 31 32 65 78 65 20 2d 4c 69 73 74 41 76 61 69 6c 61 62 6c 65 20 2d 65 61 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //2 gmo ps12exe -ListAvailable -ea SilentlyContinue
		$a_01_1 = {49 6e 73 74 61 6c 6c 2d 4d 6f 64 75 6c 65 20 70 73 31 32 65 78 65 20 2d 53 63 6f 70 65 20 43 75 72 72 65 6e 74 55 73 65 72 20 2d 46 6f 72 63 65 20 2d 65 61 20 53 74 6f 70 } //2 Install-Module ps12exe -Scope CurrentUser -Force -ea Stop
		$a_01_2 = {24 4e 65 78 74 4e 75 6d 62 65 72 20 3d 20 24 4e 75 6d 62 65 72 2b 31 } //3 $NextNumber = $Number+1
		$a_01_3 = {24 4e 65 78 74 53 63 72 69 70 74 20 3d 20 24 50 53 45 58 45 73 63 72 69 70 74 2e 52 65 70 6c 61 63 65 } //2 $NextScript = $PSEXEscript.Replace
		$a_01_4 = {24 4e 65 78 74 53 63 72 69 70 74 20 7c 20 70 73 31 32 65 78 65 20 2d 6f 75 74 70 75 74 46 69 6c 65 20 24 50 53 53 63 72 69 70 74 52 6f 6f 74 2f 24 4e 65 78 74 4e 75 6d 62 65 72 2e 65 78 65 20 2a 3e 20 24 6e 75 6c 6c } //1 $NextScript | ps12exe -outputFile $PSScriptRoot/$NextNumber.exe *> $null
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=10
 
}