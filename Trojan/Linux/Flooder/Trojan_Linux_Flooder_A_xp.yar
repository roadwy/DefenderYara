
rule Trojan_Linux_Flooder_A_xp{
	meta:
		description = "Trojan:Linux/Flooder.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 25 73 20 5b 2d 54 20 2d 55 20 2d 49 20 2d 4e 20 2d 73 20 2d 68 20 2d 64 20 2d 70 20 2d 71 20 2d 6c 20 2d 74 5d } //02 00  Usage: %s [-T -U -I -N -s -h -d -p -q -l -t]
		$a_01_1 = {69 6e 6a 65 63 74 5f 69 70 68 64 72 } //02 00  inject_iphdr
		$a_01_2 = {54 3a 55 49 4e 73 3a 68 3a 64 3a 70 3a 71 3a 6c 3a 74 3a } //01 00  T:UINs:h:d:p:q:l:t:
		$a_01_3 = {47 65 6d 69 6e 69 64 } //01 00  Geminid
		$a_01_4 = {54 43 50 20 41 74 74 61 63 6b } //00 00  TCP Attack
		$a_00_5 = {5d 04 00 00 } //74 15 
	condition:
		any of ($a_*)
 
}