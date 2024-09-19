
rule HackTool_Linux_EarthWorm_B_MTB{
	meta:
		description = "HackTool:Linux/EarthWorm.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 2f 78 78 78 20 2d 68 20 2d 73 20 73 73 6f 63 6b 73 64 } //2 ./xxx -h -s ssocksd
		$a_01_1 = {2e 2f 65 77 20 2d 73 20 72 73 73 6f 63 6b 73 20 2d 64 20 78 78 78 2e 78 78 78 2e 78 78 78 2e 78 78 78 20 2d 65 20 38 38 38 38 } //2 ./ew -s rssocks -d xxx.xxx.xxx.xxx -e 8888
		$a_01_2 = {72 6f 6f 74 6b 69 74 65 72 2e 63 6f 6d 2f 45 61 72 74 68 57 72 6f 6d 2f } //1 rootkiter.com/EarthWrom/
		$a_01_3 = {2e 2f 65 77 20 2d 73 20 6c 63 78 5f 73 6c 61 76 65 20 2d 64 20 5b 72 65 66 5f 69 70 5d } //1 ./ew -s lcx_slave -d [ref_ip]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}