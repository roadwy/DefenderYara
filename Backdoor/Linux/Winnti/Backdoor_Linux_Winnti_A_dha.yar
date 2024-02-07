
rule Backdoor_Linux_Winnti_A_dha{
	meta:
		description = "Backdoor:Linux/Winnti.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5b 61 64 76 4e 65 74 53 72 76 5d 20 63 61 6e 20 6e 6f 74 20 63 72 65 61 74 65 20 61 20 50 46 5f 49 4e 45 54 20 73 6f 63 6b 65 74 } //01 00  [advNetSrv] can not create a PF_INET socket
		$a_00_1 = {2f 75 73 72 2f 73 62 69 6e 2f 64 6d 69 64 65 63 6f 64 65 20 20 7c 20 67 72 65 70 20 2d 69 20 27 55 55 49 44 27 20 7c 63 75 74 20 2d 64 27 20 27 20 2d 66 32 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c } //01 00  /usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null
		$a_00_2 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 } //01 00  CONNECT %s:%d HTTP/1.0
		$a_00_3 = {48 49 44 45 5f 54 48 49 53 5f 53 48 45 4c 4c 3d } //00 00  HIDE_THIS_SHELL=
	condition:
		any of ($a_*)
 
}