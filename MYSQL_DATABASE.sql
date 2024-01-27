--
-- Table structure for table `follows`
--

DROP TABLE IF EXISTS `follows`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `follows` (
  `id` int NOT NULL AUTO_INCREMENT,
  `follower_id` int DEFAULT NULL,
  `following_id` int DEFAULT NULL,
  PRIMARY KEY (`id`)
)

--
-- Dumping data for table `follows`
--

LOCK TABLES `follows` WRITE;
/*!40000 ALTER TABLE `follows` DISABLE KEYS */;
INSERT INTO `follows` VALUES (1,1,2),(2,2,1);
/*!40000 ALTER TABLE `follows` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `likes`
--

DROP TABLE IF EXISTS `likes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `likes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `short_id` int DEFAULT NULL,
  `user_id` int DEFAULT NULL,
  PRIMARY KEY (`id`)
)

--
-- Dumping data for table `likes`
--

LOCK TABLES `likes` WRITE;
/*!40000 ALTER TABLE `likes` DISABLE KEYS */;
INSERT INTO `likes` VALUES (20,3,1),(21,4,1),(22,1,1),(23,2,1),(24,10,1),(25,12,1),(30,3,1),(51,6,1),(52,8,1),(53,7,1);
/*!40000 ALTER TABLE `likes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `oauth_tokens`
--

DROP TABLE IF EXISTS `oauth_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `token` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`)
)

--
-- Dumping data for table `oauth_tokens`
--

LOCK TABLES `oauth_tokens` WRITE;
/*!40000 ALTER TABLE `oauth_tokens` DISABLE KEYS */;
/*!40000 ALTER TABLE `oauth_tokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `shorts`
--

DROP TABLE IF EXISTS `shorts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `shorts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(65) DEFAULT NULL,
  `url` varchar(60) DEFAULT NULL,
  `user_id` int DEFAULT NULL,
  PRIMARY KEY (`id`)
)

--
-- Dumping data for table `shorts`
--

LOCK TABLES `shorts` WRITE;
/*!40000 ALTER TABLE `shorts` DISABLE KEYS */;
INSERT INTO `shorts` VALUES (2,'Cute Kitten','9manidkrogo.mp4',2),(3,'Dog and duck so cute!','prOXIp07esM.mp4',2),(6,'Godot in 100 Seconds','QKgTZWbwD1U.mp4',1),(7,'Unity in 100 Seconds','iqlH4okiQqg.mp4',1),(8,'Unreal in 100 Seconds','DXDe-2BC4cE.mp4',1),(9,'Bash in 100 Seconds','I4EWvMFj37g.mp4',1),(11,'SVG Explained in 100 Seconds','emFMHH2Bfvo.mp4',1),(12,'VS Code in 100 Seconds','KMxo3T_MTvY.mp4',1),(13,'Python in 100 Seconds','x7X9w_GIm1s.mp4',1),(14,'C in 100 Seconds','U3aXWizDbQ4.mp4',1),(15,'Java in 100 Seconds','l9AzO1FMgM8.mp4',1),(16,'HTML in 100 Seconds','ok-plXXHlWw.mp4',1),(20,'This Laptop changes everything! #laptop #framework','H3lwNOb8iRE.mp4',1),(21,'7 Things We Like About The Pixel 7A','vt8TwrL-Bpg.mp4',1);
/*!40000 ALTER TABLE `shorts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(65) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  `cover_photo_url` varchar(300) DEFAULT 'assets/black.jpg',
  `is_admin` int DEFAULT '0',
  `first_name` varchar(45) DEFAULT NULL,
  `last_name` varchar(45) DEFAULT NULL,
  `bio` varchar(245) DEFAULT NULL,
  `location` varchar(45) DEFAULT NULL,
  `website` varchar(45) DEFAULT NULL,
  `email` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username_UNIQUE` (`username`)
)

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918','https://external-content.duckduckgo.com/iu/?u=http%3A%2F%2Fmytechshout.com%2Fwp-content%2Fuploads%2F2014%2F10%2FFacebook-Cover-Photos-8.jpg&f=1&nofb=1&ipt=5beb4f795ccdb552ebe419146c45a13ba4701e01cbcb4ad24b9e6dc470a0d74c&ipo=images',1,'John','Smith','I am the Admin','Toronto, ON, CA','https://example.com','0');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `watches`
--

DROP TABLE IF EXISTS `watches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `watches` (
  `id` int NOT NULL AUTO_INCREMENT,
  `short_id` int DEFAULT NULL,
  `user_id` int DEFAULT NULL,
  PRIMARY KEY (`id`)
)

--
-- Dumping data for table `watches`
--

LOCK TABLES `watches` WRITE;
/*!40000 ALTER TABLE `watches` DISABLE KEYS */;
INSERT INTO `watches` VALUES (1,2,1),(2,1,1),(3,3,1),(4,4,1),(5,5,1),(6,9,1),(7,6,1),(8,7,1),(9,8,1),(10,19,1),(11,12,1),(12,2,12),(13,1,12),(14,3,12),(15,4,12),(16,5,12),(17,19,12),(18,12,12),(19,6,12),(20,7,12),(21,8,12),(22,9,12),(23,2,16),(24,1,16),(25,3,16),(26,2,18),(27,1,18),(28,3,18),(29,2,19),(30,1,19),(31,3,19),(32,4,19),(33,5,19),(34,9,19),(35,12,19),(36,6,19),(37,7,19),(38,8,19);
/*!40000 ALTER TABLE `watches` ENABLE KEYS */;
UNLOCK TABLES;
