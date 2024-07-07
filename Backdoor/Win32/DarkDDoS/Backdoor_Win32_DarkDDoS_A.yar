
rule Backdoor_Win32_DarkDDoS_A{
	meta:
		description = "Backdoor:Win32/DarkDDoS.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 00 61 00 52 00 4b 00 20 00 44 00 44 00 6f 00 53 00 65 00 52 00 20 00 76 00 } //3 DaRK DDoSeR v
		$a_01_1 = {53 00 74 00 61 00 74 00 75 00 73 00 3a 00 20 00 5b 00 20 00 49 00 63 00 6d 00 70 00 20 00 2d 00 20 00 41 00 74 00 74 00 61 00 63 00 6b 00 20 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 20 00 5d 00 } //3 Status: [ Icmp - Attack Enabled ]
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}