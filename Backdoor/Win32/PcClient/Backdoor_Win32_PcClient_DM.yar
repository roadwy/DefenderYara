
rule Backdoor_Win32_PcClient_DM{
	meta:
		description = "Backdoor:Win32/PcClient.DM,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 0c 00 00 "
		
	strings :
		$a_01_0 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //10 RegisterServiceCtrlHandlerA
		$a_01_1 = {57 53 41 44 75 70 6c 69 63 61 74 65 53 6f 63 6b 65 74 41 } //10 WSADuplicateSocketA
		$a_01_2 = {53 59 53 54 45 4d 5c 43 55 52 52 45 4e 54 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 45 52 56 49 43 45 53 5c } //2 SYSTEM\CURRENTControlSet\SERVICES\
		$a_01_3 = {43 6f 6e 6e 65 63 54 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 } //2 ConnecTion: Keep-Alive
		$a_01_4 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 } //2 \svchost.exe -k 
		$a_01_5 = {25 30 32 64 25 30 34 64 25 30 34 64 2f 25 30 32 64 25 30 32 64 25 30 32 64 2f 25 64 2e 6a 73 70 } //1 %02d%04d%04d/%02d%02d%02d/%d.jsp
		$a_01_6 = {47 6c 6f 62 61 6c 5c 25 73 2d 6f 72 65 2d 6d 65 74 75 78 } //1 Global\%s-ore-metux
		$a_01_7 = {47 6c 6f 62 61 6c 5c 25 73 2d 6f 72 65 2d 45 56 45 4e 54 } //1 Global\%s-ore-EVENT
		$a_01_8 = {25 30 35 78 2e 74 6e 70 } //1 %05x.tnp
		$a_01_9 = {25 73 25 30 37 78 2e 69 6d 69 } //1 %s%07x.imi
		$a_01_10 = {53 65 72 76 65 65 65 44 6f } //1 ServeeeDo
		$a_01_11 = {46 69 6e 64 46 69 63 6b 65 64 } //1 FindFicked
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=31
 
}