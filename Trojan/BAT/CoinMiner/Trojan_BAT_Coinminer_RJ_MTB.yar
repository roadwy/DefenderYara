
rule Trojan_BAT_Coinminer_RJ_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 75 72 65 64 67 62 63 70 5c } //1 nuredgbcp\
		$a_01_1 = {4c 61 6e 6d 4b 74 6d 52 6d 2e 65 78 65 } //1 LanmKtmRm.exe
		$a_01_2 = {4c 61 6e 64 6d 69 6e 65 2e 65 78 65 } //1 Landmine.exe
		$a_01_3 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 45 76 65 6e 74 43 6f 6e 73 75 6d 65 72 20 57 48 45 52 45 20 4e 61 6d 65 3d 22 42 42 42 42 42 42 22 } //1 CommandLineEventConsumer WHERE Name="BBBBBB"
		$a_01_4 = {50 41 54 48 20 5f 5f 45 76 65 6e 74 46 69 6c 74 65 72 20 57 48 45 52 45 20 4e 61 6d 65 3d 22 41 41 41 41 41 41 22 } //1 PATH __EventFilter WHERE Name="AAAAAA"
		$a_01_5 = {2a 48 75 54 61 6f 43 6f 6e 66 69 67 2a } //1 *HuTaoConfig*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}