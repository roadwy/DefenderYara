
rule Trojan_Win32_Zbot_EM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {75 bb 92 76 b8 91 78 b6 90 7a b4 8f 7b b1 8d 7d af 8c 7f ac 8b 80 aa 8a 82 a8 88 84 a5 87 85 a3 86 87 a0 85 89 9e 83 8b 9c 82 8c 99 81 8e 97 80 90 94 7e 91 92 7d 93 8f 7c 95 8d 7a 96 8b 79 98 } //02 00 
		$a_01_1 = {74 00 67 00 75 00 78 00 77 00 69 00 6f 00 6f 00 6e 00 72 00 62 00 67 00 61 00 61 00 6c 00 6f 00 70 00 6b 00 63 00 76 00 6a 00 } //00 00  tguxwioonrbgaalopkcvj
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 65 00 2d 00 6f 00 70 00 65 00 6e 00 70 00 68 00 6f 00 6e 00 65 00 2e 00 6f 00 72 00 67 00 } //01 00  de-openphone.org
		$a_81_1 = {36 34 41 44 30 36 32 35 } //01 00  64AD0625
		$a_01_2 = {64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 77 00 73 00 6e 00 70 00 6f 00 65 00 6d 00 2e 00 73 00 79 00 73 00 } //01 00  drivers\wsnpoem.sys
		$a_01_3 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 70 00 6f 00 72 00 74 00 6f 00 70 00 65 00 6e 00 69 00 6e 00 67 00 20 00 54 00 43 00 50 00 20 00 36 00 30 00 38 00 31 00 20 00 52 00 50 00 43 00 } //01 00  netsh firewall add portopening TCP 6081 RPC
		$a_81_4 = {39 31 43 33 38 39 30 35 } //00 00  91C38905
	condition:
		any of ($a_*)
 
}