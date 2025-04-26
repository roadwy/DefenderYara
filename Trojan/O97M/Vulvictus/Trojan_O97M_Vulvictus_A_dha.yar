
rule Trojan_O97M_Vulvictus_A_dha{
	meta:
		description = "Trojan:O97M/Vulvictus.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 6e 65 74 5f 75 73 65 72 5f 25 75 73 65 72 6e 61 6d 65 25 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 20 3e 3e 25 74 65 6d 70 25 } //2 echo ---------- net_user_%username% ----------  >>%temp%
		$a_01_1 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 56 65 72 73 69 6f 6e 20 4f 66 20 4f 53 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d } //1 ---------- Version Of OS ----------
		$a_01_2 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 65 63 68 6f 20 20 66 69 72 65 77 61 6c 6c 5f 72 75 6c 65 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d } //1 ---------- echo  firewall_rule ----------
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}