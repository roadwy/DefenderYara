
rule Trojan_BAT_Strictor_GP_MTB{
	meta:
		description = "Trojan:BAT/Strictor.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {6b 69 6c 6c 4d 43 } //2 killMC
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {46 6c 61 73 68 53 65 74 74 69 6e 67 73 2e 74 78 74 } //1 FlashSettings.txt
		$a_81_3 = {4d 69 6e 65 63 72 61 66 74 20 53 74 65 61 6c 65 72 } //4 Minecraft Stealer
		$a_81_4 = {73 65 72 76 65 72 73 2e 64 61 74 } //1 servers.dat
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*4+(#a_81_4  & 1)*1) >=10
 
}