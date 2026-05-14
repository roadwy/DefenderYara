
rule Trojan_BAT_Remcos_AMTB{
	meta:
		description = "Trojan:BAT/Remcos!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 68 69 72 6f 73 67 75 69 64 65 2e 68 75 2f 74 69 2f } //https://hirosguide.hu/ti/  2
		$a_80_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 55 48 68 48 75 55 2e 65 78 65 } //C:\ProgramData\UHhHuU.exe  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}