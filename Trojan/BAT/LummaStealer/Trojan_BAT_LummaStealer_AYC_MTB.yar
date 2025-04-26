
rule Trojan_BAT_LummaStealer_AYC_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 73 69 63 6f 6c 6f 67 69 61 65 63 75 6c 74 75 72 61 2e 63 6f 6d 2e 62 72 } //2 psicologiaecultura.com.br
		$a_01_1 = {66 75 6e 63 74 69 6f 6e 20 48 69 64 65 2d 43 6f 6e 73 6f 6c 65 } //1 function Hide-Console
		$a_01_2 = {53 74 61 72 74 52 76 72 53 68 65 6c 6c } //1 StartRvrShell
		$a_01_3 = {69 66 20 28 24 65 78 65 4e 61 6d 65 20 2d 65 71 20 22 52 53 47 61 6d 65 2e 65 78 65 22 29 } //1 if ($exeName -eq "RSGame.exe")
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}