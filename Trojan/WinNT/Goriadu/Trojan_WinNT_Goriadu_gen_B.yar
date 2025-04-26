
rule Trojan_WinNT_Goriadu_gen_B{
	meta:
		description = "Trojan:WinNT/Goriadu.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 5f 68 65 61 6c 74 68 5f 69 6e 66 6f 2e 70 68 70 } //3 file_health_info.php
		$a_01_1 = {67 65 6f 2e 6b 61 73 70 65 72 73 6b 79 2e 63 6f 6d } //1 geo.kaspersky.com
		$a_01_2 = {63 75 30 31 30 2e 77 77 77 2e 64 75 62 61 2e 6e 65 74 } //2 cu010.www.duba.net
		$a_01_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 50 00 61 00 73 00 73 00 74 00 68 00 72 00 75 00 } //3 \DosDevices\Passthru
		$a_01_4 = {4e 64 69 73 47 65 74 50 6f 6f 6c 46 72 6f 6d 50 61 63 6b 65 74 } //2 NdisGetPoolFromPacket
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=11
 
}