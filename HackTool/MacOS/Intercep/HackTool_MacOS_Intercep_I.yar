
rule HackTool_MacOS_Intercep_I{
	meta:
		description = "HackTool:MacOS/Intercep.I,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {49 6e 74 65 72 63 65 70 74 65 72 2d 4e 47 90 02 06 5b 43 6f 6e 73 6f 6c 65 20 45 64 69 74 69 6f 6e 5d 90 00 } //1
		$a_00_1 = {73 6e 69 66 66 2e 73 75 } //1 sniff.su
		$a_00_2 = {73 79 73 63 74 6c 20 2d 77 20 6e 65 74 2e 69 6e 65 74 2e 69 70 2e 66 6f 72 77 61 72 64 69 6e 67 3d 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c } //1 sysctl -w net.inet.ip.forwarding=1 > /dev/null
		$a_00_3 = {53 74 61 72 74 20 43 61 70 74 75 72 69 6e 67 } //1 Start Capturing
		$a_00_4 = {53 74 61 72 74 20 41 52 50 20 50 6f 69 73 6f 6e 69 6e 67 } //1 Start ARP Poisoning
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}