
rule Backdoor_BAT_Famtrat_A_bit{
	meta:
		description = "Backdoor:BAT/Famtrat.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 00 7a 00 6d 00 6f 00 6e 00 65 00 79 00 65 00 7a 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 } //3 ezmoneyez.ddns.net
		$a_01_1 = {5c 46 41 52 41 54 43 4c 49 45 4e 54 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 41 52 41 54 43 4c 49 45 4e 54 2e 70 64 62 } //2 \FARATCLIENT\obj\Debug\FARATCLIENT.pdb
		$a_01_2 = {46 00 41 00 56 00 49 00 52 00 55 00 53 00 3a 00 } //2 FAVIRUS:
		$a_01_3 = {66 61 73 74 61 79 6b 6f 2e 63 68 69 63 6b 65 6e 6b 69 6c 6c 65 72 2e 63 6f 6d } //1 fastayko.chickenkiller.com
		$a_01_4 = {47 72 61 62 44 65 73 6b 74 6f 70 } //1 GrabDesktop
		$a_01_5 = {53 65 6e 64 44 65 73 6b 74 6f 70 49 6d 61 67 65 } //1 SendDesktopImage
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}