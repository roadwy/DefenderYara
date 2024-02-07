
rule Backdoor_Win32_Sensode_G{
	meta:
		description = "Backdoor:Win32/Sensode.G,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 68 61 63 6b 73 69 74 65 } //01 00  -hacksite
		$a_01_1 = {7a 78 61 72 70 73 2e 65 78 65 20 2d 69 64 78 20 30 20 2d 69 70 20 31 39 32 2e 31 36 38 2e 30 2e 32 2d 31 39 32 2e 31 36 38 2e 30 2e 39 39 20 2d 70 6f 72 74 20 38 30 20 2d 68 61 63 6b 73 69 74 65 20 32 32 32 2e 32 2e 32 2e 32 } //01 00  zxarps.exe -idx 0 -ip 192.168.0.2-192.168.0.99 -port 80 -hacksite 222.2.2.2
		$a_01_2 = {2d 68 61 63 6b 64 6e 73 20 5b 73 74 72 69 6e 67 5d 20 20 44 4e 53 } //01 00  -hackdns [string]  DNS
		$a_01_3 = {52 65 73 74 6f 72 69 6e 67 20 74 68 65 20 41 52 50 54 61 62 6c 65 2e 2e 2e 2e 2e 2e } //01 00  Restoring the ARPTable......
		$a_01_4 = {4b 69 6c 6c 69 6e 67 20 74 68 65 20 53 70 6f 6f 66 54 68 72 65 61 64 2e 2e 2e 2e 2e 2e } //01 00  Killing the SpoofThread......
		$a_01_5 = {68 61 63 6b 73 69 74 65 3a 20 25 73 20 2d 3e 20 25 73 2e } //00 00  hacksite: %s -> %s.
	condition:
		any of ($a_*)
 
}