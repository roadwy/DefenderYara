
rule HackTool_Linux_PNScan_A_MTB{
	meta:
		description = "HackTool:Linux/PNScan.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 70 76 34 62 6f 74 2e 77 68 61 74 69 73 6d 79 69 70 61 64 64 72 65 73 73 2e 63 6f 6d 3a } //01 00  ipv4bot.whatismyipaddress.com:
		$a_00_1 = {70 6e 73 63 61 6e 5d 20 73 74 61 72 74 69 6e 67 20 70 6e 73 63 61 6e } //01 00  pnscan] starting pnscan
		$a_00_2 = {73 65 74 6d 69 6e 65 72 63 6d 64 } //01 00  setminercmd
		$a_02_3 = {3a 2f 2f 77 77 77 2e 6c 79 73 61 74 6f 72 2e 6c 69 75 2e 73 65 2f 7e 70 65 6e 2f 70 6e 73 63 61 6e 90 02 15 43 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 6f 70 74 69 6f 6e 73 3a 90 00 } //01 00 
		$a_00_4 = {70 6f 6f 6c 2e 73 75 70 70 6f 72 74 78 6d 72 2e 63 6f 6d 27 20 3e 3e 20 2f 65 74 63 2f 68 6f 73 74 73 3b 65 63 68 6f 20 27 30 2e 30 2e 30 2e 30 20 70 69 6e 74 6f 2e 6d 61 6d 6f 69 6e 74 65 72 6e 65 74 2e 69 63 75 27 20 3e 3e 20 2f 65 74 63 2f 68 6f 73 74 73 3b } //01 00  pool.supportxmr.com' >> /etc/hosts;echo '0.0.0.0 pinto.mamointernet.icu' >> /etc/hosts;
		$a_00_5 = {61 6e 74 69 5d 20 5b 73 75 73 70 69 63 69 6f 6e 5d 20 5b 6b 69 6c 6c 5d 20 69 73 20 74 65 6c 6e 65 74 } //01 00  anti] [suspicion] [kill] is telnet
		$a_00_6 = {6d 76 20 25 73 2f 78 6d 72 69 67 20 25 73 } //01 00  mv %s/xmrig %s
		$a_00_7 = {63 61 72 20 2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 20 7c 20 25 73 20 70 72 69 6e 74 66 20 35 31 32 20 2f 74 6d 70 2f 73 6c 69 6d 65 20 3e 3e 20 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 72 63 53 } //00 00  car /proc/self/exe | %s printf 512 /tmp/slime >> /etc/init.d/rcS
	condition:
		any of ($a_*)
 
}