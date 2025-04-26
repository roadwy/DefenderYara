
rule Trojan_BAT_Killav_W{
	meta:
		description = "Trojan:BAT/Killav.W,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 25 62 75 6c 6c 73 68 69 74 25 25 6d 70 66 25 25 5f 25 6c 25 73 61 72 73 25 25 71 73 6b 25 25 70 67 35 36 25 25 6d 73 6e 25 25 66 25 20 25 71 25 25 2e 25 25 77 25 25 72 6d 61 25 25 67 36 66 25 25 61 76 70 5f 63 6c 75 62 25 26 25 74 65 6e 25 25 2f 25 25 72 61 6d 25 25 78 25 25 62 25 } //1 %%bullshit%%mpf%%_%l%sars%%qsk%%pg56%%msn%%f% %q%%.%%w%%rma%%g6f%%avp_club%&%ten%%/%%ram%%x%%b%
	condition:
		((#a_01_0  & 1)*1) >=1
 
}