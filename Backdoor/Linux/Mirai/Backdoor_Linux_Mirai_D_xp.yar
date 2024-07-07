
rule Backdoor_Linux_Mirai_D_xp{
	meta:
		description = "Backdoor:Linux/Mirai.D!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {34 72 33 73 20 62 30 74 6e 33 74 } //1 4r3s b0tn3t
		$a_00_1 = {69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50 } //1 iptables -A INPUT -p tcp --destination-port 5555 -j DROP
		$a_00_2 = {73 68 20 6c 6f 6c 2e 73 68 } //1 sh lol.sh
		$a_00_3 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 15 2f 62 69 6e 64 2f 61 2e 73 68 20 2d 4f 20 2d 20 3e 20 6c 6f 6c 2e 73 68 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}